
rule o3e9_153128e29ac3691a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.153128e29ac3691a"
     cluster="o3e9.153128e29ac3691a"
     cluster_size="694"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['00b4418c609897cfd2353cde0fbcbfd7','01e3d8e2de4c0b229163665318fa474c','072bc8f7c8e19aaf3ecced6ac40f0b36']"

   strings:
      $hex_string = { d5fa5075de3eb5c94811a5f4cea2165cca7e1c9d3683a855a0b07a44f05e65cf4b0f18ae7f4ac90508274f6276cd9b86cb0d0158182972c270fc30271b50ac50 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
