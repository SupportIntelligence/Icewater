
rule p2321_6b9a92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p2321.6b9a92b9c8800b12"
     cluster="p2321.6b9a92b9c8800b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector delf gate"
     md5_hashes="['2c53853c02143a19fb2c0e8fb59ba471','320038d5287938dc5d1d5ccecf46d30b','b819de570f95704c3f34f2274facd011']"

   strings:
      $hex_string = { 0c5aa0cbfa032175a777f8c5f46766f748865cc93de60893cdf64cde0e33a33238319b5390a9dceda1a52e026afb1bd6912f18d9ecccc1548207f3b68efdac10 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
