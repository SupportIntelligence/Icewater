
rule m3e9_0e38954315b84346
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0e38954315b84346"
     cluster="m3e9.0e38954315b84346"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy eydrop"
     md5_hashes="['42418e94b722761da6fe9d88056be1cd','55751884a61c35d53b09acd258bfcf2e','da72e2f20a1ce3b34ca5db0986c26672']"

   strings:
      $hex_string = { 21eaebd02404f92ca3282e6b208fbaa79ce4d42910a841e1cc132dedb8694d64a2d70551e3d29979b285ca9b1adbc963782a19390834af466183e07584c6936d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
