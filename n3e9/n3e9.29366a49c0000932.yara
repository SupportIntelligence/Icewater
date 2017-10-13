import "hash"

rule n3e9_29366a49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29366a49c0000932"
     cluster="n3e9.29366a49c0000932"
     cluster_size="1215 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="barys gamarue lilu"
     md5_hashes="['04edf2806d547aba5dd7b02fbc05b521', '56b2dbf6d896a93fa5a1e147a39cf36d', '02da410be030ef8a23364b5a0dbfc482']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(200704,1024) == "01b20baab45567cd2ae288e7857c154d"
}

