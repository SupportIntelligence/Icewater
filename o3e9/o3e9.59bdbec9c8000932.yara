
rule o3e9_59bdbec9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59bdbec9c8000932"
     cluster="o3e9.59bdbec9c8000932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock symmi nabucur"
     md5_hashes="['b0689b65adc9fa4797555cc00c09731d','b23e92fa4c8ac363e5c5028974ae4e71','f033b5db8d928b9703068031d9c35e79']"

   strings:
      $hex_string = { ebf2f900dde6ee00aebac300c3cbd500c4cfd700bac5d3007b829500b8c1cc009db2d20040527200364a4f0057902b005d9c2a0066af2d006ab12e006db33300 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
