
rule m26bb_01b994a69a9b4916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.01b994a69a9b4916"
     cluster="m26bb.01b994a69a9b4916"
     cluster_size="137"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ransom gandcrab generickdz"
     md5_hashes="['f92ae2bb33dce58b389b5c236447e10850ad7af4','5013c922ebfa83f6fd266b6a0b6e9f6f0df691f9','f5779d6395bbae993f61afde7278f32e1986eeb3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.01b994a69a9b4916"

   strings:
      $hex_string = { 8d46185750e817c0ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
