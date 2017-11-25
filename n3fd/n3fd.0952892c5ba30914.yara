
rule n3fd_0952892c5ba30914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fd.0952892c5ba30914"
     cluster="n3fd.0952892c5ba30914"
     cluster_size="267"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo acerace"
     md5_hashes="['017f40d5b9073a5c11941c256e944db3','02969ad1b198d6d5397017c3c43b3beb','142bbe6458a808d3473cddb2ca9a14ab']"

   strings:
      $hex_string = { 6c696e67006765745f436f6e7665727465727300446573657269616c697a65006335313661323031616166616435313833316437376363613436343264396232 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
