
rule k2319_1e1256a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1256a9c8800b12"
     cluster="k2319.1e1256a9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['396d24b8d02f49fa7f0d20a434c5a2ac05ab58c7','50f1f08f56aec1c7f387ca6c071fd1106f7ea552','487d5514147e3da4163d5ee28b7202ddc43a5b14']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1256a9c8800b12"

   strings:
      $hex_string = { 65616b7d3b666f72287661722050304d20696e206c3444304d297b69662850304d2e6c656e6774683d3d3d2828307843372c342e35394532293c2839362e2c31 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
