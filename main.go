// +build !js

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GRVYDEV/lightspeed-webrtc/ws"
	"github.com/gorilla/websocket"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"

	"github.com/microsoft/iron-go"
)

type Session struct {
	Issuer string `json:"issuer"`
	PublicAddress string `json:"publicAddress"`
	Email string `json:"email"`
	CreatedAt float64 `json:"createdAt"`
	MaxAge float64 `json:"maxAge"`
}
func (s *Session) GetCreatedAt() float64 {
	return s.CreatedAt
}
func (s *Session) GetMaxAge() float64 {
	return s.MaxAge
}

var (
	addr           = flag.String("addr", "localhost", "http service address")
	ip             = flag.String("ip", "none", "IP address for webrtc")
	wsPort         = flag.Int("ws-port", 8080, "Port for websocket")
	rtpPort        = flag.Int("rtp-port", 65535, "Port for RTP")
	ports          = flag.String("ports", "20000-20500", "Port range for webrtc")
	sslCert        = flag.String("ssl-cert", "", "Ssl cert for websocket (optional)")
	sslKey         = flag.String("ssl-key", "", "Ssl key for websocket (optional)")
	tokenSecret    = flag.String("token-secret", "", "Secret for cookie auth (optional)")
	allowedOrigin  = flag.String("origin", "*", "Allowed origin(s), can be empty or * to allow all origins, or a comma-separated list of origins (optional)")
	strictOrigin   = flag.Bool("strict-origin", false, "Whether or not to use strict origin checking (forbids empty origin header) (optional)")

	videoTrack *webrtc.TrackLocalStaticRTP

	audioTrack *webrtc.TrackLocalStaticRTP

	hub *ws.Hub

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { 
			if (allowedOrigin == nil || *allowedOrigin == "" || *allowedOrigin == "*") {
				log.Print("Allowing all origins")

				return true
			}

			origin := r.Header.Get("Origin")
			if (origin == "") {
				isStrict := strictOrigin != nil && *strictOrigin
				log.Print("Origin not provided, strict? ", isStrict)

				return !isStrict
			}

			allowedOrigins := strings.Split(*allowedOrigin, ",")
			

			for _, v := range allowedOrigins {
				if origin == v {
					log.Print("Requset from allowed origin, ", v)

					return true
				}
			}

			log.Print("Request not from allowed origin, ", origin)

			return false
		},
	}
)

func main() {
	flag.Parse()
	log.SetFlags(0)

	// Open a UDP Listener for RTP Packets on port 65535
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(*addr), Port: *rtpPort})
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	}()

	fmt.Println("Waiting for RTP Packets")

	// Create a video track
	videoTrack, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: "video/h264"}, "video", "pion")
	if err != nil {
		panic(err)
	}

	// Create an audio track
	audioTrack, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: "audio/opus"}, "video", "pion")
	if err != nil {
		panic(err)
	}

	hub = ws.NewHub()
	go hub.Run()

	// start HTTP server
	go func() {
		http.HandleFunc("/websocket", websocketHandler)

		wsAddr := *addr+":"+strconv.Itoa(*wsPort)
		if *sslCert != "" && *sslKey != "" {
			log.Fatal(http.ListenAndServeTLS(wsAddr, *sslCert, *sslKey, nil))
		} else {
			log.Fatal(http.ListenAndServe(wsAddr, nil))
		}
	}()

	inboundRTPPacket := make([]byte, 4096) // UDP MTU

	// Read RTP packets forever and send them to the WebRTC Client
	for {

		n, _, err := listener.ReadFrom(inboundRTPPacket)

		if err != nil {
			fmt.Printf("error during read: %s", err)
			panic(err)
		}

		packet := &rtp.Packet{}
		if err = packet.Unmarshal(inboundRTPPacket[:n]); err != nil {
			//It has been found that the windows version of OBS sends us some malformed packets
			//It does not effect the stream so we will disable any output here
			//fmt.Printf("Error unmarshaling RTP packet %s\n", err)
		}

		if packet.Header.PayloadType == 96 {
			if _, writeErr := videoTrack.Write(inboundRTPPacket[:n]); writeErr != nil {
				panic(writeErr)
			}
		} else if packet.Header.PayloadType == 97 {
			if _, writeErr := audioTrack.Write(inboundRTPPacket[:n]); writeErr != nil {
				panic(writeErr)
			}
		}

	}

}

// Create a new webrtc.API object that takes public IP addresses and port ranges into account.
func createWebrtcApi() *webrtc.API {
	s := webrtc.SettingEngine{}

	// Set a NAT IP if one is given
	if *ip != "none" {
		s.SetNAT1To1IPs([]string{*ip}, webrtc.ICECandidateTypeHost)
	}

	// Split given port range into two sides, pass them to SettingEngine
	pr := strings.SplitN(*ports, "-", 2)

	pr_low, err := strconv.ParseUint(pr[0], 10, 16)
	if err != nil {
		panic(err)
	}
	pr_high, err := strconv.ParseUint(pr[1], 10, 16)
	if err != nil {
		panic(err)
	}

	s.SetEphemeralUDPPortRange(uint16(pr_low), uint16(pr_high))

	// Default parameters as specified in Pion's non-API NewPeerConnection call
	// These are needed because CreateOffer will not function without them
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		panic(err)
	}

	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		panic(err)
	}

	return webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i), webrtc.WithSettingEngine(s))
}

// Handle incoming websockets
func websocketHandler(w http.ResponseWriter, r *http.Request) {
	success, err := checkAuthCookie(r)
	if (!success) {
		log.Print("Failed to validate the authentication cookie: ", err)
		
		return
	}

	// Upgrade HTTP request to Websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}

	// When this frame returns close the Websocket
	defer conn.Close() //nolint

	// Create API that takes IP and port range into account
	api := createWebrtcApi()

	// Create new PeerConnection
	peerConnection, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Print(err)
		return
	}

	// When this frame returns close the PeerConnection
	defer peerConnection.Close() //nolint

	// Accept one audio and one video track Outgoing
	transceiverVideo, err := peerConnection.AddTransceiverFromTrack(videoTrack,
		webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendonly,
		},
	)
	if err != nil {
		log.Print(err)
		return
	}

	transceiverAudio, err := peerConnection.AddTransceiverFromTrack(audioTrack,
		webrtc.RTPTransceiverInit{
			Direction: webrtc.RTPTransceiverDirectionSendonly,
		},
	)
	if err != nil {
		log.Print(err)
		return
	}
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, rtcpErr := transceiverVideo.Sender().Read(rtcpBuf); rtcpErr != nil {
				return
			}
			if _, _, rtcpErr := transceiverAudio.Sender().Read(rtcpBuf); rtcpErr != nil {
				return
			}
		}
	}()

	c := ws.NewClient(hub, conn, peerConnection)

	go c.WriteLoop()

	// Add to the hub
	hub.Register <- c

	// Trickle ICE. Emit server candidate to client
	peerConnection.OnICECandidate(func(i *webrtc.ICECandidate) {
		if i == nil {
			return
		}

		candidateString, err := json.Marshal(i.ToJSON())
		if err != nil {
			log.Println(err)
			return
		}

		if msg, err := json.Marshal(ws.WebsocketMessage{
			Event: ws.MessageTypeCandidate,
			Data:  candidateString,
		}); err == nil {
			hub.RLock()
			if _, ok := hub.Clients[c]; ok {
				c.Send <- msg
			}
			hub.RUnlock()
		} else {
			log.Println(err)
		}
	})

	// If PeerConnection is closed remove it from global list
	peerConnection.OnConnectionStateChange(func(p webrtc.PeerConnectionState) {
		switch p {
		case webrtc.PeerConnectionStateFailed:
			if err := peerConnection.Close(); err != nil {
				log.Print(err)
			}
			hub.Unregister <- c

		case webrtc.PeerConnectionStateClosed:
			hub.Unregister <- c
		}
	})

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		log.Print(err)
	}

	if err = peerConnection.SetLocalDescription(offer); err != nil {
		log.Print(err)
	}

	offerString, err := json.Marshal(offer)
	if err != nil {
		log.Print(err)
	}

	if msg, err := json.Marshal(ws.WebsocketMessage{
		Event: ws.MessageTypeOffer,
		Data:  offerString,
	}); err == nil {
		hub.RLock()
		if _, ok := hub.Clients[c]; ok {
			c.Send <- msg
		}
		hub.RUnlock()
	} else {
		log.Printf("could not marshal ws message: %s", err)
	}

	c.ReadLoop()
}

func checkAuthCookie(r *http.Request) (success bool, err error) {
	nowS := time.Now().Unix()
	
	var secret string
	if (tokenSecret == nil) {
		log.Print("No secret provided, skipping auth cookie check")

		return true, nil
	}
	secret = *tokenSecret
	if (secret == "") {
		log.Print("Secret empty, skipping auth cookie check")

		return true, nil
	}
	
	unsealer := iron.New(iron.Options{Secret: []byte(secret)})
	
	sealedToken, err := r.Cookie("token")

	if (err != nil) {
		return false, err
	}

	unsealedToken, err := unsealer.Unseal(sealedToken.Value)
	if (err != nil) {
		return false, err
	}
	// for some reason there are control characters being added after the "}", maybe the golang iron isn't stripping the padding the JS iron adds, idk if it adds padding?
	token := bytes.Trim(unsealedToken, "\x06")

	var session Session
	err = json.Unmarshal(token, &session)
	if (err != nil) {
		return false, err
	}

	expiresAt := session.GetCreatedAt() + session.GetMaxAge()
	if (float64(nowS) > expiresAt) {
		return false, errors.New("Session has expired")
	}

	return true, nil
}