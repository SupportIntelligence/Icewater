
rule k3e9_3164bcc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3164bcc1c8000932"
     cluster="k3e9.3164bcc1c8000932"
     cluster_size="100105"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd bublik zbot"
     md5_hashes="['00004c073f61545ddd233b547d90b738','0001882b740701270c1a2a671b25dce7','00116affed68154ee20c0a516dd38f1e']"

   strings:
      $hex_string = { a12015849b22c0f599d12847c612eb5936401c51d0e69cd2af042c210cfb81548fa74c930882091af791a28d440a944f0f896ab586c4e8118cec384d50e4a0e3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
