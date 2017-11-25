
rule m3e9_11b96b2437496b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b96b2437496b16"
     cluster="m3e9.11b96b2437496b16"
     cluster_size="34"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic zbot kryptik"
     md5_hashes="['243b79de8ac059b757032ef78ea622cb','304ed7082e71103fc585530dcda391e2','c3920a706c5fff2e4417f9a97588a28f']"

   strings:
      $hex_string = { 8642623b874d2e3a8755d23ce881b08ffa83725ec345aa6a00003684088bfb967ec037e244f4ad1de00fc13902390b976e59bd25e883de760074f3e34ce8b511 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
