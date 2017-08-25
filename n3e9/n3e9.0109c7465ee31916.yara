import "hash"

rule n3e9_0109c7465ee31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c7465ee31916"
     cluster="n3e9.0109c7465ee31916"
     cluster_size="1431 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious syncopate moderate"
     md5_hashes="['294bdf2dab457bf9d54e966fce6e8b3f', '289f4ebdde7ac43d364dc8e57dd68ca3', '13601ba79d273f8fe974fc6331ff9ef3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(293343,1035) == "81501d626e5d4c6c4d7dd0223334ce12"
}

