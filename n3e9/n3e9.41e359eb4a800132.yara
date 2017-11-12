
rule n3e9_41e359eb4a800132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.41e359eb4a800132"
     cluster="n3e9.41e359eb4a800132"
     cluster_size="67"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="parite pate pinfi"
     md5_hashes="['07f9b986f9d23b0df03cc73763e0796a','08bee975e082b14993190917f797bd52','4928b54d0f5a07fc4375e728dee6c094']"

   strings:
      $hex_string = { 2b3029060355040b1322436f70797269676874202863292032303030204d6963726f736f667420436f72702e312330210603550403131a4d6963726f736f6674 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
