
rule o26bb_432da969d3930932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.432da969d3930932"
     cluster="o26bb.432da969d3930932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious malwarex"
     md5_hashes="['7167629c1a0013cef3486c074c417777d03e7605','f9767d9fc44f579dec572be209adf95cbcef5e19','22ab3cd7aa976a80b9bca77af77abe26bff8caf1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.432da969d3930932"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
