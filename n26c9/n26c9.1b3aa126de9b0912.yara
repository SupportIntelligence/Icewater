
rule n26c9_1b3aa126de9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.1b3aa126de9b0912"
     cluster="n26c9.1b3aa126de9b0912"
     cluster_size="119"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer malicious badfile"
     md5_hashes="['10b786d2aba317a0d85ce94efbdab94720dd41e4','46128e81776bb6d0a2e59d7c534ae765e84a0663','a23fa20ef8bc7bf27a1536a57f8b07dd5a879078']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.1b3aa126de9b0912"

   strings:
      $hex_string = { c1ff15466908000fb6134c8bf04c8bc084d27426908d4ae080f95e760c8d42f73c01760580fa0d750641881049ffc00fb6530148ffc384d275db45882048c7c1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
