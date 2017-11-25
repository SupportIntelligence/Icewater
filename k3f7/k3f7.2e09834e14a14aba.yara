
rule k3f7_2e09834e14a14aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2e09834e14a14aba"
     cluster="k3f7.2e09834e14a14aba"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['4213e6fd00f05dd03ee647385a8ff938','75b5a1f5c70535a564100bd35c869985','cb8ac79695b0b2da07e8bfda13abe9bf']"

   strings:
      $hex_string = { 312f762d6373732f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
