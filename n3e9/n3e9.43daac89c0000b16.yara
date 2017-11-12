
rule n3e9_43daac89c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.43daac89c0000b16"
     cluster="n3e9.43daac89c0000b16"
     cluster_size="269"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chinky vobfus vbkrypt"
     md5_hashes="['010e16c353b3342033c4e785622b40c3','048a52d6d494a90e55f0ca7f595e7668','212ca222ed20244cddcf62126b50bfb8']"

   strings:
      $hex_string = { 7202ffd58b4e7c8b54242c33c0c70439000000005f5e5d6689025b83c408c214008b4c242c5f33c05e5d6689015b83c408c21400909090909090909090909090 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
