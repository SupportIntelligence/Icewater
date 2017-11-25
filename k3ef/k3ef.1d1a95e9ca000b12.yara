
rule k3ef_1d1a95e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.1d1a95e9ca000b12"
     cluster="k3ef.1d1a95e9ca000b12"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious attribute"
     md5_hashes="['432b4d0a873bd258097ec1ebb29e6d5a','43c4ad03e0ca48de337d3bcc04517bd4','f9c82f18275f202362e582b35318fef5']"

   strings:
      $hex_string = { 425a5f444154415f4552524f523a2063667461625b7b307d5d3d7b317d206c6173743d7b327d000073747265616d20636f727275707465640000626c6f636b53 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
