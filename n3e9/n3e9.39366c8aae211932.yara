import "hash"

rule n3e9_39366c8aae211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39366c8aae211932"
     cluster="n3e9.39366c8aae211932"
     cluster_size="1156 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0cb9102ac7efc1e87f2ae0738028ce7e', '5c396d22c0504524929f56ccea8441c8', '43c9a209e4d7ba4a6ebebf006f7e292b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(61440,1024) == "821913283c3a548032a8ee12e97d41d2"
}

