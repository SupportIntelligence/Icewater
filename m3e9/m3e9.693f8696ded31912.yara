
rule m3e9_693f8696ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f8696ded31912"
     cluster="m3e9.693f8696ded31912"
     cluster_size="389"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0020003fa3ac2afc2a8c0e86f4273ccf','00470c7519e39e58f15465003100973f','04a9a63cf6bfa865fc2e099597fae4ec']"

   strings:
      $hex_string = { aa36394a513048cd456c8da2529d85576c1b1dabf98c21e02575a859045c23746d541adc99f56d57cb9c5748129bee18774e9508a7bdc2d0b8967db6aafc4ad8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
