
rule p26e5_19bd9cc144001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26e5.19bd9cc144001932"
     cluster="p26e5.19bd9cc144001932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious attribute"
     md5_hashes="['b695ad7a7c4f0539c3a476a03d3c88531a4cf834','906d96044045db10e42e80ed0d82d6879106ca56','47fe9b0b83a01d2b678b6c62db9fabcd5c682d0a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26e5.19bd9cc144001932"

   strings:
      $hex_string = { 0000080a4a192136181e45185d1403ec1454d05d58ca2f2d125f0afa21c72f36bcf86fc5d8c254b91c7b541e18be997bb428f945bbda2f0740a3e5cd0e0a0808 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
