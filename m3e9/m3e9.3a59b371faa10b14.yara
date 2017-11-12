
rule m3e9_3a59b371faa10b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a59b371faa10b14"
     cluster="m3e9.3a59b371faa10b14"
     cluster_size="720"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking fujacks malicious"
     md5_hashes="['00beaa2a0bc7d5e9f8d808e296a3a293','04f9eb89c143de28f8098be8d581c42e','230977513eca74a6f737f28deb3eccff']"

   strings:
      $hex_string = { 290ff7890319d0cf4f87ca8ab0371e60acf8a283e236f21558c64a3d796e8cbf608f0ea528d11a3fcb012f32ec1792612474a70c66c3b6667f1f82cbe3380716 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
