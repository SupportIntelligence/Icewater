
rule m2321_019e9eb9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.019e9eb9c9800b12"
     cluster="m2321.019e9eb9c9800b12"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy shifu cfca"
     md5_hashes="['297cf89f0c3037b9612e5c8fc2df7909','5d4ebdc20128707a69b0e3c275954ba0','b574763174b1334707460df78b63579e']"

   strings:
      $hex_string = { 5294d48b025a3ff39d3b21ef5d741343bfb000830b4ebc1c56fa87ad1b8e11e4ca7371677f61de4008ee4d48cb7e27f5dcd1e8b1d079a4d820c80c0582da3816 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
