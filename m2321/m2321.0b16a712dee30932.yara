
rule m2321_0b16a712dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b16a712dee30932"
     cluster="m2321.0b16a712dee30932"
     cluster_size="4"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery dynamer pemalform"
     md5_hashes="['3e8a55738869fd94e483268d6db3dbab','51865e76604d28224ed972f5746b82dc','d9518ecf40c2f2f228bde560667068fe']"

   strings:
      $hex_string = { 825772b8cd1290bc21b2a24e40381bcc70da6b02f91deb5ebb07c04c7db36328dd807891cb7594880b65d3a78cbe53f3e7e62d732ce1b5339c98e4604d08ffb9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
