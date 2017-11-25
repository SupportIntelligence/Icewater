
rule j3e9_2cc679209d996b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.2cc679209d996b12"
     cluster="j3e9.2cc679209d996b12"
     cluster_size="164"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd bublik"
     md5_hashes="['0c4a6696c566120594a90fdd4c2edf56','15b50519d0a862267cb609e79c7a39c5','3bfd9507ce9523cabea16d4b3c55b22c']"

   strings:
      $hex_string = { 1999261998261998261998261998211596382ea1d4d2ec403c9f2b22952417973930a2d4d2ec716abbd4d2eca29dd1271a99392fa2d4d2ec2b209b2014962518 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
