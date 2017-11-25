
rule m3ed_3ed94b1716b14ade
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3ed94b1716b14ade"
     cluster="m3ed.3ed94b1716b14ade"
     cluster_size="68"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy quchispy trojanspy"
     md5_hashes="['01780ac2f6b920c47a3a4dac663327a1','03e52d5385c0e1f79beebcde9dde232d','55ff76caff791fd6b42959b499352b68']"

   strings:
      $hex_string = { 00011890c60feee0c139b4cf095c78c52be6f7440e4cc293fcfba11520600d0568e22a10b087022071150ca8628cd258e00766f98138c41213b3e480142c11be }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
