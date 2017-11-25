
rule k3f7_6c24b8e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6c24b8e9c8800b12"
     cluster="k3f7.6c24b8e9c8800b12"
     cluster_size="70"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html hiddenlink"
     md5_hashes="['02fae760e728612b5b90eb516c5b1e3b','0cf395a43dc544256ecdee4d44a1a768','47cbd51b3ddefa428bf49bbc6439a4bd']"

   strings:
      $hex_string = { 696e672e66726f6d43686172436f6465287061727365496e742874292b32352d6c2b61293b0d0a0d0a743d27273b7d7d785b6c2d615d3d7a3b7d646f63756d65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
