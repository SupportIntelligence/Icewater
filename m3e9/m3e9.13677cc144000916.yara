
rule m3e9_13677cc144000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13677cc144000916"
     cluster="m3e9.13677cc144000916"
     cluster_size="80"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['086face822e1d4d30ce4dbc4517c8fc3','1244b8591c99a87f0ffab465137a9936','4dae0241606e2270a055fea4b2ffe595']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
