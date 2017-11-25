
rule m3f7_49304442ddeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.49304442ddeb0912"
     cluster="m3f7.49304442ddeb0912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['017f1540a50db446a8f975d1d354106a','40fd2363a014f943132b7d70f6557e79','cbc95c48780f0d3d9cc2b278dbe94187']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c696e6b4c6973743127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
