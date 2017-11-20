
rule m3e9_134edec9c4000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.134edec9c4000916"
     cluster="m3e9.134edec9c4000916"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted fcfcd"
     md5_hashes="['106fa31088b1315be12eeca3a2eeaff7','1ecf97d1cdb3f982ffc49b50a6887ab9','ae51db0b2114621bd1d4b1f76e92a5f0']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
