
rule m2321_23954ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.23954ab9c9800b16"
     cluster="m2321.23954ab9c9800b16"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['0e6a9cacdc33043e1aefb02764b918e9','346bd5014076e102414d0e1d392a6278','e15a071fba50e77d30c2d0478798907f']"

   strings:
      $hex_string = { 9fec3ed28838dedd767483255d93b9d56b680784127332a84ea33305ac7e973504dfafbfaf0ebecc95a03aadedfbdbe21f3dfae9e14002f2349c09b130c5b88d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
