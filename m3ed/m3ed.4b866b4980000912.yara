
rule m3ed_4b866b4980000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b866b4980000912"
     cluster="m3ed.4b866b4980000912"
     cluster_size="122"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="microfake nitol ddos"
     md5_hashes="['00000babf103463376cfeffc256298ab','009dca75cfbc4973ac3a1e6749628d06','1b56d6b2b04e26dce8e3b83a2c6be43f']"

   strings:
      $hex_string = { b934c634d334eb34fd340a3510351d3523353f357b35bb35e135fd350e36143620362c3652365f3685369136a636bd36e336e83605372a372f37453767376d37 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
