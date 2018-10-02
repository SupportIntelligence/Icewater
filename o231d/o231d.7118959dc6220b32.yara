
rule o231d_7118959dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.7118959dc6220b32"
     cluster="o231d.7118959dc6220b32"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp androidos riskware"
     md5_hashes="['4e1652ad317aa0554df510c1350804dae1f13cf2','6277e50e316b70f121324566df43645686d678df','0a1a14c0fd8c27ad3f9457400f68d9432886321b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.7118959dc6220b32"

   strings:
      $hex_string = { 0af8e2c5bd5a2dfd81fb4afc2f9e18fe98d611924bafb97a9c72680ea6c65845ef7ba907042bcfbada5ee863c703ed023579c07c3946f3430df4dbb7744d87ee }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
