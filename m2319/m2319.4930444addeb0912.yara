
rule m2319_4930444addeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4930444addeb0912"
     cluster="m2319.4930444addeb0912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['5281fcea9d1c4cd5d942fb2728dd33f2','676e39c3250d16c5ae321e5a996fd1cc','a8c36d690936725cd46c1a1094c89e3c']"

   strings:
      $hex_string = { 6f63756d656e742e676574456c656d656e744279496428274c696e6b4c6973743227292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
