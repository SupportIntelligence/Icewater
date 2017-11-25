
rule m3ed_3ed94b931eb34ade
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3ed94b931eb34ade"
     cluster="m3ed.3ed94b931eb34ade"
     cluster_size="98"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy quchispy spyware"
     md5_hashes="['092d1f07dc564d1e5ecbb02951383d5a','0c72d7cca42a93c56b71d6afcb443131','4392e8358a69e4a28cebd44b58a1000d']"

   strings:
      $hex_string = { 00011890c60feee0c139b4cf095c78c52be6f7440e4cc293fcfba11520600d0568e22a10b087022071150ca8628cd258e00766f98138c41213b3e480142c11be }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
