
rule m2321_0aa14c423543485a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0aa14c423543485a"
     cluster="m2321.0aa14c423543485a"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['2df54748cb8293bb18406a647b5a9653','6333b48247ba0205d1017cf6bde3460d','f26427da3cc16cebe6e8f148a74ec6a7']"

   strings:
      $hex_string = { 21a80a816797f4dcb6505b4e0b55e5b86e3a3fe310741619b700c7f73e4f6ac33da70ea162c4ded7b5c0ae2c42e013ba36e186296349f9d60414f865c1efb44a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
