
rule n3e9_49169ed1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.49169ed1c4000912"
     cluster="n3e9.49169ed1c4000912"
     cluster_size="70"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi smja"
     md5_hashes="['05d25b4149b2fae37620b98bc9aa0ada','0972ad7a83908f7926ed2891bd3995d1','a7163c97f18539f67dcc9a588e21e6bb']"

   strings:
      $hex_string = { 4f04b838c240008947088b45dc5689470cff9290030000dbe285c07d12689003000068f0bc40005650ff15a410400068c6434400eb148d4de0518d55e4526a02 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
