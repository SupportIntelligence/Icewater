
rule n3e9_3bb19492d98bbb35
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3bb19492d98bbb35"
     cluster="n3e9.3bb19492d98bbb35"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious startsurf bscope"
     md5_hashes="['406b0f18e56612e8797852c376bee922','aeb7d36522383817243bdc92f65352d3','ef68d216d086f2244f74a8a6f957dd5f']"

   strings:
      $hex_string = { 000aa849444154785eeddd4b681dd719c0f1e36e85e82360d45d2abcb35de1141ccbd0048304ad1d709d0706ef6548b292dc820d86666150ba915749b0bd9636 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
