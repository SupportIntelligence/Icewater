import "hash"

rule n3e9_69147949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.69147949c0000b12"
     cluster="n3e9.69147949c0000b12"
     cluster_size="53378 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="symmi gamarue buzus"
     md5_hashes="['0192a5c4b6e5947a26c74e21969c1981', '01748c390f09715224765fd580294ffd', '02dfc66c2c5471250983f39d24ffeea6']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(93184,1024) == "0fbb3e7ed88cf1ab34fd422bb0b5f7be"
}

