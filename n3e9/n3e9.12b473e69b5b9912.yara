
rule n3e9_12b473e69b5b9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.12b473e69b5b9912"
     cluster="n3e9.12b473e69b5b9912"
     cluster_size="127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi script delf"
     md5_hashes="['03a83cfed77c82aebecfe2d0f31b436c','0418eb825a3f4cfd4b4ff12d7ab66eee','335d53358ad2f5d713ce77b5703ef869']"

   strings:
      $hex_string = { 8a494210ac4fe53a6e07b152d9fad2920c6118cbcb3c2329cc4db848b08257112d8d053e04ba095b5aaed55697124cd300a53801b2b72754a2a15ef8e377c146 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
