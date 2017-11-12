
rule o3e9_1651a8629ed36b1a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1651a8629ed36b1a"
     cluster="o3e9.1651a8629ed36b1a"
     cluster_size="523"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['00a68564fc3118c09bbf6c8d9454dfc1','02054e750be6e13ab3aba3103c32a02a','09a7608afe13467c670b3b1cfa121b3f']"

   strings:
      $hex_string = { ba281dd9124fa5723a4c10807c2c75b80f2dc0bfe52f2bd1c029a0e28fa18fd100169662ddb8d8c3d9879e6501d2bd7a3ef2348fddeae1f6ef8d81acb2cbacff }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
