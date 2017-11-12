
rule n3ed_39957a4dc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a4dc6620b32"
     cluster="n3ed.39957a4dc6620b32"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['1c79c7cf891390cdc83916a0a9b5d925','31254707867e24f099a93730c456e412','8350efcaff81bddc23b781f00652ef74']"

   strings:
      $hex_string = { 8b451483c00b394510c606007709e85a3effff6a22ebc08b7d088b078945f48b47048bc8c1e914baff0700005323ca33db3bca0f859000000085db0f85880000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
