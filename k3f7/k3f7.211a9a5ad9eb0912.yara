
rule k3f7_211a9a5ad9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.211a9a5ad9eb0912"
     cluster="k3f7.211a9a5ad9eb0912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['8778bdc8959deeaab1f0e650e87a9bfc','a47b053f112b0274f7f8ae12502043d7','fd83b7edf928a8ce8f09ca7ae7e4ef04']"

   strings:
      $hex_string = { 4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335382c35363739342c3832 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
