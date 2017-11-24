
rule m3e9_09b118a6d6bb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.09b118a6d6bb1916"
     cluster="m3e9.09b118a6d6bb1916"
     cluster_size="2920"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic shipup gepys"
     md5_hashes="['00438e36d809951e453bf637276f6dd1','007cdec03a7ebc176db381002c303e5d','034f1253a9bfdca02d56de481f3f9e02']"

   strings:
      $hex_string = { a3430a74f406934d1f2d38606a08e4c92f26b5c39b141db9e87ad4ab23c04012b3bca5aaae6f618b80b8ed1a01f0d5ced7bf9403bbdf5d8fbe6430472c25ba71 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
