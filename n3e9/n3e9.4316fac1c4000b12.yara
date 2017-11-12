
rule n3e9_4316fac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4316fac1c4000b12"
     cluster="n3e9.4316fac1c4000b12"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['0ea347f44892b37b8152416b0a0a8986','1155317c717d151c20b0ec1ee9033670','c48d8d0c90f104484e9c479ee2bfd5bf']"

   strings:
      $hex_string = { 50e897cafcff8d45e450e88ecafcffc38d45e050e884cafcffc38b4df064890d000000005f5e5bc9c3558bec5151680649400064a10000000050648925000000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
