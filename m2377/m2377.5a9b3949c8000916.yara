
rule m2377_5a9b3949c8000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.5a9b3949c8000916"
     cluster="m2377.5a9b3949c8000916"
     cluster_size="52"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['04aa519664c2d15b589b82eaed6d5a60','062a87f9a91ee95834427a45a7f5282b','4e0f1c6b869dec5ac2c05069997abf7e']"

   strings:
      $hex_string = { 1b1397b3116d28d52444220a53e888036ed9ea0c4010e54bdd961e2034175b9e62c02d083b9ffe49b6bf47a5d45cf952e404212e6bdba62399891c3068fb310f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
