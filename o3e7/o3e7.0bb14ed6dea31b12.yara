
rule o3e7_0bb14ed6dea31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0bb14ed6dea31b12"
     cluster="o3e7.0bb14ed6dea31b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dlboost malicious installmonstr"
     md5_hashes="['5892596287965e25ff36cd188ce4a755','8f64c94114c2b7adf824a365e1f98cf2','b78722fade78220e5208a0ffc6602011']"

   strings:
      $hex_string = { dc6164185307bb96ab0fd6e8b4819e19eb724eaeaa9c16f9c2a2dd27ed3d46a926a1a757518928fc21c3c59a36e12ac6da9b339085f354a48ad32988e2fd5d59 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
