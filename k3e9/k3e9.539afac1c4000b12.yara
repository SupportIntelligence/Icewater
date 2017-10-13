import "hash"

rule k3e9_539afac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.539afac1c4000b12"
     cluster="k3e9.539afac1c4000b12"
     cluster_size="25754 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="mydoom email malicious"
     md5_hashes="['028c7e21fc9b7cec36946a565f51e86e', '0190addbb3529571dff5fc049950887f', '004873cb47487bfa92c33a32c45503b3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18944,1024) == "761dfca1f1eee46aa28db54312173457"
}

