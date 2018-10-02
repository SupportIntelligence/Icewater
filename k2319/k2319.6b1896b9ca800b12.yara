
rule k2319_6b1896b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6b1896b9ca800b12"
     cluster="k2319.6b1896b9ca800b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script crypt"
     md5_hashes="['7ab408db303635b5ad8b46ac0841643c88885ad7','10a2d3a319918cb0a7bed40849e19d288dad9087','827d128669b1404c8912386a872f022a4f63738b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6b1896b9ca800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20575b435d3b7d76617220773d2830783230343c3d283133372e2c3939293f2830783133432c226c22293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
