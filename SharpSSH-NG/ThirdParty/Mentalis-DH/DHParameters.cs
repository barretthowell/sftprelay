﻿//
// DHParameters.cs: Defines a structure that holds the parameters of the Diffie-Hellman algorithm
//
// Author:
//	Pieter Philippaerts (Pieter@mentalis.org)
//
// (C) 2003 The Mentalis.org Team (http://www.mentalis.org/)
//

using System;

namespace Org.Mentalis.Security.Cryptography
{
    /// <summary>
    /// Represents the parameters of the Diffie-Hellman algorithm.
    /// </summary>
    internal struct DHParameters
    {
        /// <summary>
        /// Represents the public <b>P</b> parameter of the Diffie-Hellman algorithm.
        /// </summary>
        public byte[] P;
        /// <summary>
        /// Represents the public <b>G</b> parameter of the Diffie-Hellman algorithm.
        /// </summary>
        public byte[] G;
        /// <summary>
        /// Represents the private <b>X</b> parameter of the Diffie-Hellman algorithm.
        /// </summary>
        public byte[] X;
    }
}