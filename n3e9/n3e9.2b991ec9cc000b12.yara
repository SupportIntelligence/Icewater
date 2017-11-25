
rule n3e9_2b991ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b991ec9cc000b12"
     cluster="n3e9.2b991ec9cc000b12"
     cluster_size="281"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="softonic softonicdownloader unwanted"
     md5_hashes="['00efb57bef100d7dd209cb3eb4d00100','00f83d834782c93c34249932d98631b8','0e25215df3ee1479af0ab7b06504f3df']"

   strings:
      $hex_string = { 0a3f9310721c0c0041f2711361c350264a3b777fef966e47e8210028c9d0561e5e616a9a53d7bbb9c7192a979dd3b4f45f07eecf7c52eac4b5206c4aa8ccbade }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
