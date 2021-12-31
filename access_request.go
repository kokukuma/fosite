/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`
	JWKThumbprint    string    `json:"jkt" gorethink:"jkt"`
	DpopProofJWT     string    `json:"dpopProofJWT" gorethink:"dpopProofJWT"`

	Request
}

func NewAccessRequest(session Session) *AccessRequest {
	r := &AccessRequest{
		GrantTypes:       Arguments{},
		HandledGrantType: Arguments{},
		JWKThumbprint:    "",
		Request:          *NewRequest(),
	}
	r.Session = session
	return r
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}

func (a *AccessRequest) GetDpopProofJWT() string {
	return a.DpopProofJWT
}

func (a *AccessRequest) SetDpopProofJWT(jwt string) {
	a.DpopProofJWT = jwt
}

func (a *AccessRequest) GetJKT() string {
	return a.JWKThumbprint
}

func (a *AccessRequest) SetJKT(jkt string) {
	a.JWKThumbprint = jkt
}

func (a *AccessRequest) DetectTokenType() string {
	// requesterしたかどうかじゃなくて、発行したトークンがsender-constrainedかどうかだよな？
	// dpopProofJWTが無効だった場合は、nilになるってことでOK?
	// strageで保存することに依存するのはいいんだろうか...?
	if a.JWKThumbprint != "" {
		return "dpop"
	}
	return "bearer"
}
