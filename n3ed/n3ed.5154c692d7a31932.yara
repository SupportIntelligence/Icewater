
rule n3ed_5154c692d7a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5154c692d7a31932"
     cluster="n3ed.5154c692d7a31932"
     cluster_size="154"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="xpaj vmprotect juklg"
     md5_hashes="['005e834f2b1302bf27fe2c4abaee23b3','022a683ad17a48136a0c981b2f751d27','16d04bb93cccd51b6fd906ebe7ab517c']"

   strings:
      $hex_string = { 242ce9f0d14df9c094fb4092ef984c20d0e888eaaaebb3fda9f4b8e591d39b855108e4eebe9f5733e78ab6ab3ee2640cb48fbd75171901af6638bad4dd4830c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
